-- TN-91, L0-META-20, OP-153 m.17 (b), m.25 (a): the recipient's contribution to an ownership
-- handover is its own `accept_root` contribute Exercise; the row keeps its ExerciseID, which the
-- completing `anchor_transfer` presents as a proof, and it is set together with contributed_at
SET LOCAL ROLE access_migrator;

ALTER TABLE access.org_transfers
  ADD COLUMN acceptance bytea CHECK (acceptance IS NULL OR octet_length(acceptance) = 32);

CREATE OR REPLACE FUNCTION access.org_transfer_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL
     OR (OLD.contributed_at IS NOT NULL AND NEW.contributed_at IS DISTINCT FROM OLD.contributed_at)
     OR (OLD.acceptance IS NOT NULL AND NEW.acceptance IS DISTINCT FROM OLD.acceptance)
     OR (OLD.contributed_at IS NULL AND (NEW.acceptance IS NULL) <> (NEW.contributed_at IS NULL))
     OR NEW.nonce <> OLD.nonce OR NEW.payload_digest <> OLD.payload_digest
     OR NEW.effective_at <> OLD.effective_at OR NEW.to_subject <> OLD.to_subject
     OR NEW.from_subject <> OLD.from_subject OR NEW.org_id <> OLD.org_id THEN
    RAISE EXCEPTION 'transfer transition not allowed' USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

GRANT UPDATE (acceptance) ON access.org_transfers TO access_app;

RESET ROLE;
