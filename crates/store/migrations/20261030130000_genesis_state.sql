-- L0-META-7, OP-141 m.6: the objects Genesis creates are state at version 0, the Genesis
-- position
SET LOCAL ROLE access_migrator;

ALTER TABLE access.authority_state DROP CONSTRAINT authority_state_version_check;
ALTER TABLE access.authority_state ADD CONSTRAINT authority_state_version_check CHECK (version >= 0);
ALTER TABLE access.authority_version DROP CONSTRAINT authority_version_version_check;
ALTER TABLE access.authority_version ADD CONSTRAINT authority_version_version_check CHECK (version >= 0);

RESET ROLE;
