-- OP-134 m.4, OP-143 m.10, OP-150 m.3 (h): every new identity audit checkpoint carries its
-- signed note from the cell's audit-checkpoint key; rows written before signing keep NULL
SET LOCAL ROLE access_migrator;

ALTER TABLE access_ops.audit_checkpoint ADD COLUMN note text
  CHECK (octet_length(note) <= 262144);
ALTER TABLE access_ops.audit_checkpoint ADD CONSTRAINT audit_checkpoint_signed
  CHECK (note IS NOT NULL) NOT VALID;

RESET ROLE;
