-- no-transaction
-- OP-158 m.3 (f), OP-55: a mirror stream reads the checkpoints of a size range, built without
-- locking writes
CREATE INDEX CONCURRENTLY IF NOT EXISTS authority_checkpoint_size
  ON access.authority_checkpoint (domain_id, size);
