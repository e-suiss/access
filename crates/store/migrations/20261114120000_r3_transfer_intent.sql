-- TN-91, L0-META-20, §9.14.1, OP-153 m.25 (i) (2): an ownership handover keeps the intent digest
-- of the anchor_transfer its proposal opened, the target the recipient's accept_root contribution
-- names through the Approval Surface; it is set with the proposal and never changes
SET LOCAL ROLE access_migrator;

ALTER TABLE access.org_transfers
  ADD COLUMN intent_digest bytea CHECK (intent_digest IS NULL OR octet_length(intent_digest) = 32);

CREATE OR REPLACE FUNCTION access.org_transfer_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL
     OR (OLD.contributed_at IS NOT NULL AND NEW.contributed_at IS DISTINCT FROM OLD.contributed_at)
     OR (OLD.acceptance IS NOT NULL AND NEW.acceptance IS DISTINCT FROM OLD.acceptance)
     OR (OLD.contributed_at IS NULL AND (NEW.acceptance IS NULL) <> (NEW.contributed_at IS NULL))
     OR NEW.intent_digest IS DISTINCT FROM OLD.intent_digest
     OR NEW.nonce <> OLD.nonce OR NEW.payload_digest <> OLD.payload_digest
     OR NEW.effective_at <> OLD.effective_at OR NEW.to_subject <> OLD.to_subject
     OR NEW.from_subject <> OLD.from_subject OR NEW.org_id <> OLD.org_id THEN
    RAISE EXCEPTION 'transfer transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

RESET ROLE;
