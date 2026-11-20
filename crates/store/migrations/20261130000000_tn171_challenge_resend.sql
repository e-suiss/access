-- TN-171: a flow may ask again; the open challenge it replaces ends as superseded and stays.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.identity_address_challenges
  DROP CONSTRAINT identity_address_challenges_status_check,
  ADD CONSTRAINT identity_address_challenges_status_check
    CHECK (status IN ('open', 'completed', 'expired', 'failed', 'superseded')) NOT VALID;

RESET ROLE;
