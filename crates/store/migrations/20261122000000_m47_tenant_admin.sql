-- OP-159 m.47, TN-138, TN-139, TN-140, TN-141, TN-142, TNI-14, TN-89, TN-109, OP-73:
-- tenant administrators and the management environment.
--
-- tenants.display_name: the tenant's own text (untrusted input, TN-131); never authority (TN-1).
-- environments.kind: `standard` or `management`; one management environment per tenant (TN-138).
-- tenant_foundings: the invited founder of a tenant and the slug its management environment will
--   take; the link token and the magic code are kept as SHA-256 only, the founder as the blind
--   index the management environment will use (TN-89 (1), (8), TN-141). A founding completes or
--   is reinvited, never removed.
-- Slugs are unique across environments and foundings (TN-16, TN-20).
-- tenant_admins: who administers the tenant, kept in its management environment; owners root
--   every environment (m.47 (e)); a new administrator from another verified domain waits (TN-109).
-- tenant_admin_claims: the `tenant_administration` line of each administrator in each consuming
--   domain, which the restate job renews and the removal ends (m.47 (f)).
-- console_session_instances: the console session's device Instance in each domain it reads
--   (TN-142); the session's single Instance columns stay as they are.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.tenants
  ADD COLUMN display_name text CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 120);

ALTER TABLE access.environments
  ADD COLUMN kind text NOT NULL DEFAULT 'standard' CHECK (kind IN ('standard', 'management'));
GRANT SELECT (kind) ON access.environments TO access_router;

CREATE FUNCTION access.environment_kind_fixed() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF NEW.kind IS DISTINCT FROM OLD.kind THEN
    RAISE EXCEPTION 'environment kind is fixed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER environment_kind_fixed BEFORE UPDATE ON access.environments
  FOR EACH ROW EXECUTE FUNCTION access.environment_kind_fixed();

CREATE TABLE access.tenant_foundings (
  tenant_id uuid NOT NULL,
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
  management_environment_id uuid NOT NULL,
  -- pii:none
  founder_index bytea NOT NULL CHECK (octet_length(founder_index) = 32),
  token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
  created_exercise bytea NOT NULL CHECK (octet_length(created_exercise) = 32),
  issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  reinvites integer NOT NULL DEFAULT 0 CHECK (reinvites >= 0),
  verified_at timestamptz,
  completed_at timestamptz,
  founder_subject uuid,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '30 days'),
  CHECK ((completed_at IS NULL) = (founder_subject IS NULL)),
  CHECK (completed_at IS NULL OR verified_at IS NOT NULL),
  PRIMARY KEY (tenant_id),
  UNIQUE (tenant_id, token_hash),
  FOREIGN KEY (tenant_id) REFERENCES access.tenants (tenant_id)
);

-- TN-16, TN-20: a reserved slug is global, as an environment's
CREATE UNIQUE INDEX tenant_foundings_slug ON access.tenant_foundings (slug);
CREATE INDEX tenant_foundings_token ON access.tenant_foundings (token_hash);

-- TN-141: a founding is verified once and completed once; a reinvitation replaces the secrets of
-- a pending founding only; what it names never changes
CREATE FUNCTION access.tenant_founding_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'foundings are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.completed_at IS NOT NULL
     OR NEW.tenant_id <> OLD.tenant_id OR NEW.slug <> OLD.slug
     OR NEW.management_environment_id <> OLD.management_environment_id
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
CREATE TRIGGER tenant_founding_transition BEFORE UPDATE OR DELETE ON access.tenant_foundings
  FOR EACH ROW EXECUTE FUNCTION access.tenant_founding_transition();

-- TN-16, TN-20: one slug space over environments and foundings; only the founding's own management
-- environment takes its slug
CREATE FUNCTION access.slug_space() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
DECLARE
  v_slug text;
BEGIN
  IF TG_TABLE_NAME = 'tenant_foundings' THEN
    v_slug := NEW.slug;
  ELSE
    v_slug := NEW.slug;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('access.slug:' || v_slug, 0));
  IF TG_TABLE_NAME = 'tenant_foundings' THEN
    IF EXISTS (SELECT 1 FROM access.environments e WHERE e.slug = v_slug) THEN
      RAISE EXCEPTION 'slug taken' USING ERRCODE = 'unique_violation';
    END IF;
  ELSIF EXISTS (SELECT 1 FROM access.tenant_foundings f
                 WHERE f.slug = v_slug
                   AND NOT (f.tenant_id = NEW.tenant_id AND f.management_environment_id = NEW.environment_id
                            AND NEW.kind = 'management')) THEN
    RAISE EXCEPTION 'slug taken' USING ERRCODE = 'unique_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER slug_space BEFORE INSERT ON access.tenant_foundings
  FOR EACH ROW EXECUTE FUNCTION access.slug_space();
CREATE TRIGGER slug_space BEFORE INSERT ON access.environments
  FOR EACH ROW EXECUTE FUNCTION access.slug_space();

-- TN-141: the founding route finds a founding by its link token before any tenant is known; it
-- learns the tenant, the slug and the state, nothing else
CREATE FUNCTION access.founding_by_token(p_token_hash bytea)
  RETURNS TABLE (tenant_id uuid, management_slug text, management_environment_id uuid, expires_at timestamptz,
                 verified boolean, completed boolean)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
  SELECT f.tenant_id, f.slug, f.management_environment_id, f.expires_at,
         f.verified_at IS NOT NULL, f.completed_at IS NOT NULL
    FROM access.tenant_foundings f
   WHERE f.token_hash = p_token_hash
$$;

-- TN-141: the tenant whose founding reserved a slug, for the local plan that founds it
CREATE FUNCTION access.founding_tenant(p_slug text) RETURNS uuid
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
  SELECT f.tenant_id FROM access.tenant_foundings f WHERE f.slug = p_slug
$$;

-- TN-16: whether a slug is free across environments and foundings, read by the platform surface
CREATE FUNCTION access.slug_free(p_slug text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
  SELECT NOT EXISTS (SELECT 1 FROM access.environments e WHERE e.slug = p_slug)
     AND NOT EXISTS (SELECT 1 FROM access.tenant_foundings f WHERE f.slug = p_slug)
$$;

CREATE TABLE access.tenant_admins (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  party_id bytea CHECK (party_id IS NULL OR octet_length(party_id) = 16),
  owner boolean NOT NULL DEFAULT false,
  added_exercise bytea CHECK (added_exercise IS NULL OR octet_length(added_exercise) = 32),
  added_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  cooling_until timestamptz,
  owner_since timestamptz,
  ended_at timestamptz,
  ended_exercise bytea CHECK (ended_exercise IS NULL OR octet_length(ended_exercise) = 32),
  CHECK (owner = (owner_since IS NOT NULL)),
  CHECK (NOT owner OR party_id IS NOT NULL),
  CHECK (cooling_until IS NULL OR cooling_until > added_at),
  CHECK (ended_at IS NOT NULL OR ended_exercise IS NULL),
  PRIMARY KEY (tenant_id, environment_id, subject_id),
  FOREIGN KEY (tenant_id, environment_id) REFERENCES access.environments (tenant_id, environment_id)
);

-- m.47 (e), (f): an administrator becomes an owner once and is removed once; ownership never
-- comes with a cooling first acceptance
CREATE FUNCTION access.tenant_admin_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant administrators are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.owner AND NEW.cooling_until IS NOT NULL THEN
      RAISE EXCEPTION 'no ownership at a first acceptance' USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.ended_at IS NOT NULL
     OR NEW.subject_id <> OLD.subject_id OR NEW.added_at <> OLD.added_at
     OR NEW.added_exercise IS DISTINCT FROM OLD.added_exercise
     OR NEW.cooling_until IS DISTINCT FROM OLD.cooling_until
     OR (OLD.party_id IS NOT NULL AND NEW.party_id IS DISTINCT FROM OLD.party_id)
     OR (OLD.owner AND NOT NEW.owner)
     OR (OLD.owner_since IS NOT NULL AND NEW.owner_since IS DISTINCT FROM OLD.owner_since) THEN
    RAISE EXCEPTION 'tenant administrator transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER tenant_admin_transition BEFORE INSERT OR UPDATE OR DELETE ON access.tenant_admins
  FOR EACH ROW EXECUTE FUNCTION access.tenant_admin_transition();

CREATE TABLE access.tenant_admin_claims (
  tenant_id uuid NOT NULL,
  environment_id uuid NOT NULL,
  subject_id uuid NOT NULL,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  claim_id bytea CHECK (claim_id IS NULL OR octet_length(claim_id) = 16),
  stated_ms bigint CHECK (stated_ms IS NULL OR stated_ms > 0),
  valid_until_ms bigint CHECK (valid_until_ms IS NULL OR valid_until_ms > 0),
  ended_ms bigint,
  ended_claim_id bytea CHECK (ended_claim_id IS NULL OR octet_length(ended_claim_id) = 16),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK ((claim_id IS NULL) = (stated_ms IS NULL) AND (claim_id IS NULL) = (valid_until_ms IS NULL)),
  CHECK (ended_claim_id IS NULL OR ended_ms IS NOT NULL),
  PRIMARY KEY (tenant_id, environment_id, subject_id, domain_id),
  FOREIGN KEY (tenant_id, environment_id, subject_id)
    REFERENCES access.tenant_admins (tenant_id, environment_id, subject_id)
);
CREATE INDEX tenant_admin_claims_due ON access.tenant_admin_claims (valid_until_ms)
  WHERE ended_ms IS NULL;

-- m.47 (f): the tenants the restate job visits; it learns tenant ids, nothing else
CREATE FUNCTION access.tenant_admin_due(p_before_ms bigint) RETURNS SETOF uuid
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
AS $$
  SELECT DISTINCT c.tenant_id FROM access.tenant_admin_claims c
   WHERE (c.ended_ms IS NULL AND (c.valid_until_ms IS NULL OR c.valid_until_ms <= p_before_ms))
      OR (c.ended_ms IS NOT NULL AND c.ended_claim_id IS NULL AND c.claim_id IS NOT NULL)
   ORDER BY 1
$$;

-- the Party of a line is fixed and an ended line stays ended
CREATE FUNCTION access.tenant_admin_claim_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'administration lines are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.party_id <> OLD.party_id OR NEW.domain_id <> OLD.domain_id
     OR (OLD.ended_ms IS NOT NULL AND (NEW.ended_ms IS DISTINCT FROM OLD.ended_ms
         OR NEW.claim_id IS DISTINCT FROM OLD.claim_id
         OR (OLD.ended_claim_id IS NOT NULL AND NEW.ended_claim_id IS DISTINCT FROM OLD.ended_claim_id))) THEN
    RAISE EXCEPTION 'administration line transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER tenant_admin_claim_transition BEFORE UPDATE OR DELETE ON access.tenant_admin_claims
  FOR EACH ROW EXECUTE FUNCTION access.tenant_admin_claim_transition();

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenant_foundings', 'tenant_admins', 'tenant_admin_claims'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()))', t);
    EXECUTE format('CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
  -- OP-132 m.5: an administrator's rows are its management environment's
  FOREACH t IN ARRAY ARRAY['tenant_admins', 'tenant_admin_claims'] LOOP
    EXECUTE format('CREATE POLICY environment_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (environment_id = (SELECT access.environment_scope())) '
                   'WITH CHECK (environment_id = (SELECT access.environment_scope()))', t);
  END LOOP;
END
$$;

CREATE TABLE access_ops.console_session_instances (
  session_id uuid NOT NULL,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  environment_slug text NOT NULL CHECK (char_length(environment_slug) BETWEEN 1 AND 63),
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  instance_kid bytea NOT NULL CHECK (octet_length(instance_kid) = 32),
  instance_key bytea NOT NULL CHECK (octet_length(instance_key) BETWEEN 1 AND 256),
  created_ms bigint NOT NULL CHECK (created_ms > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id, domain_id),
  FOREIGN KEY (session_id) REFERENCES access_ops.console_sessions (session_id)
);
ALTER TABLE access_ops.console_session_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.console_session_instances FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.console_session_instances FROM PUBLIC;
CREATE POLICY rows ON access_ops.console_session_instances AS PERMISSIVE USING (true);
CREATE POLICY app_only ON access_ops.console_session_instances AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_app', 'MEMBER'));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access_ops.console_session_instances
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access_ops.console_session_instances
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
-- INV-13: an Instance once attached to a session in a domain stays the one
CREATE TRIGGER no_update BEFORE UPDATE ON access_ops.console_session_instances
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

-- TN-142: a registration challenge for the session's Instance in one more domain, taken once
CREATE TABLE access_ops.console_instance_challenges (
  challenge bytea NOT NULL CHECK (octet_length(challenge) = 32),
  session_id uuid NOT NULL,
  domain_id bytea NOT NULL CHECK (octet_length(domain_id) = 32),
  environment_slug text NOT NULL CHECK (char_length(environment_slug) BETWEEN 1 AND 63),
  key bytea NOT NULL CHECK (octet_length(key) BETWEEN 1 AND 256),
  party_id bytea NOT NULL CHECK (octet_length(party_id) = 16),
  from_ms bigint NOT NULL CHECK (from_ms > 0),
  until_ms bigint NOT NULL CHECK (until_ms >= from_ms),
  taken_ms bigint,
  PRIMARY KEY (challenge),
  FOREIGN KEY (session_id) REFERENCES access_ops.console_sessions (session_id)
);
ALTER TABLE access_ops.console_instance_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.console_instance_challenges FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.console_instance_challenges FROM PUBLIC;
CREATE POLICY rows ON access_ops.console_instance_challenges AS PERMISSIVE USING (true);
CREATE POLICY app_only ON access_ops.console_instance_challenges AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_app', 'MEMBER'));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access_ops.console_instance_challenges
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access_ops.console_instance_challenges
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();
GRANT SELECT, INSERT ON access_ops.console_instance_challenges TO access_app;
GRANT UPDATE (taken_ms) ON access_ops.console_instance_challenges TO access_app;

REVOKE ALL ON FUNCTION access.environment_kind_fixed() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.tenant_founding_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.slug_space() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.tenant_admin_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.tenant_admin_claim_transition() FROM PUBLIC;
REVOKE ALL ON FUNCTION access.founding_by_token(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.slug_free(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION access.founding_tenant(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.founding_tenant(text) TO access_app, access_router;
REVOKE ALL ON FUNCTION access.tenant_admin_due(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION access.tenant_admin_due(bigint) TO access_app;
GRANT EXECUTE ON FUNCTION access.founding_by_token(bytea) TO access_app, access_router;
GRANT EXECUTE ON FUNCTION access.slug_free(text) TO access_app, access_router;
GRANT SELECT, INSERT ON access.tenant_foundings, access.tenant_admins, access.tenant_admin_claims
  TO access_app;
GRANT UPDATE (token_hash, code_hash, issued_at, expires_at, reinvites, verified_at, completed_at,
  founder_subject) ON access.tenant_foundings TO access_app;
GRANT UPDATE (party_id, owner, owner_since, ended_at, ended_exercise) ON access.tenant_admins TO access_app;
GRANT UPDATE (claim_id, stated_ms, valid_until_ms, ended_ms, ended_claim_id)
  ON access.tenant_admin_claims TO access_app;
GRANT SELECT, INSERT ON access_ops.console_session_instances TO access_app;

RESET ROLE;
