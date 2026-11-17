-- OP-159 m.48 (b), (d), TN-4, TN-139, OP-73:
--
-- tenant_admin_claims.episode: one row per episode of an administrator's `tenant_administration`
--   line in a domain. An ended row never reopens; a suspended-then-reactivated administrator that was
--   not removed starts a new episode with a new row (m.48 (d)). At most one live row per line.
-- environment_domain_binding.effective_at: a consuming binding written by
--   `idp.environment.consumer_bind` holds only after the TN-4 cool-down (m.48 (b)); NULL holds since
--   it was written.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.tenant_admin_claims
  ADD COLUMN episode integer NOT NULL DEFAULT 1 CHECK (episode >= 1);
ALTER TABLE access.tenant_admin_claims DROP CONSTRAINT tenant_admin_claims_pkey;
ALTER TABLE access.tenant_admin_claims
  ADD PRIMARY KEY (tenant_id, environment_id, subject_id, domain_id, episode);

-- the Party and the episode of a line are fixed and an ended line stays ended
CREATE OR REPLACE FUNCTION access.tenant_admin_claim_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'administration lines are never deleted' USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.party_id <> OLD.party_id OR NEW.domain_id <> OLD.domain_id OR NEW.episode <> OLD.episode
     OR (OLD.ended_ms IS NOT NULL AND (NEW.ended_ms IS DISTINCT FROM OLD.ended_ms
         OR NEW.claim_id IS DISTINCT FROM OLD.claim_id
         OR (OLD.ended_claim_id IS NOT NULL AND NEW.ended_claim_id IS DISTINCT FROM OLD.ended_claim_id))) THEN
    RAISE EXCEPTION 'administration line transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.tenant_admin_claim_transition() FROM PUBLIC;

ALTER TABLE access.environment_domain_binding ADD COLUMN effective_at timestamptz;

RESET ROLE;
