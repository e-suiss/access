-- TN-158, OP-55: the widened profile field check, validated apart from its addition.
SET LOCAL ROLE access_migrator;

ALTER TABLE access.identity_profile_fields VALIDATE CONSTRAINT identity_profile_fields_field_check;

RESET ROLE;
