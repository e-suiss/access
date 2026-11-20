-- TN-167, OP-55: the recovery mark's check, validated apart from its addition.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.identity_credentials VALIDATE CONSTRAINT identity_credentials_revoked_by_revoked;

RESET ROLE;
