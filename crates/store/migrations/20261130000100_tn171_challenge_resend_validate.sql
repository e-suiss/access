-- TN-171, OP-55: the widened status check, validated apart from its change.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.identity_address_challenges VALIDATE CONSTRAINT identity_address_challenges_status_check;

RESET ROLE;
