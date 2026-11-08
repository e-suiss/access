-- OP-153 m.3 (d), TN-52, Ek B 3541: a recovery contact's code lives 24 hours and the person
-- recovering may extend it once by another 24 hours, before it runs out. The extension is the only
-- change of `expires_at` the evidence ever takes.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.recovery_evidence ADD COLUMN extended_at timestamptz;

CREATE OR REPLACE FUNCTION access.recovery_evidence_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog
  AS $$
BEGIN
  IF TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'recovery_evidence: % is not allowed', TG_OP USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    IF OLD.consumed_at IS NOT NULL OR OLD.extended_at IS NOT NULL OR NEW.extended_at IS NULL
       OR OLD.class <> 'recovery_contact' OR OLD.expires_at <= NEW.extended_at
       OR NEW.expires_at <> OLD.expires_at + interval '24 hours' THEN
      RAISE EXCEPTION 'recovery_evidence: a contact code is extended once, by 24 hours, before it runs out' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (NEW.tenant_id, NEW.realm_id, NEW.evidence_id, NEW.attempt_id, NEW.class, NEW.code_hash,
        NEW.address_id, NEW.created_at, NEW.tries_left, NEW.consumed_at)
       IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.evidence_id, OLD.attempt_id, OLD.class,
                         OLD.code_hash, OLD.address_id, OLD.created_at, OLD.tries_left, OLD.consumed_at) THEN
      RAISE EXCEPTION 'recovery_evidence: an extension changes nothing else' USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.consumed_at IS NOT NULL OR NEW.tries_left > OLD.tries_left
     OR NEW.extended_at IS DISTINCT FROM OLD.extended_at
     OR (NEW.tenant_id, NEW.realm_id, NEW.evidence_id, NEW.attempt_id, NEW.class, NEW.code_hash,
         NEW.address_id, NEW.created_at)
        IS DISTINCT FROM (OLD.tenant_id, OLD.realm_id, OLD.evidence_id, OLD.attempt_id, OLD.class,
                          OLD.code_hash, OLD.address_id, OLD.created_at) THEN
    RAISE EXCEPTION 'recovery_evidence: evidence is spent once and its tries only fall' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION access.recovery_evidence_transition() FROM PUBLIC;

GRANT UPDATE (expires_at, extended_at) ON access.recovery_evidence TO access_app;

RESET ROLE;
