-- TN-143, OP-55: the new kind check, validated without blocking writes
SET LOCAL ROLE access_migrator;

ALTER TABLE access.environments VALIDATE CONSTRAINT environments_kind_check;

RESET ROLE;
