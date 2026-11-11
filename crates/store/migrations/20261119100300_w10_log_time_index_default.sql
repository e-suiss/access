-- no-transaction
-- OP-55, OP-158 m.3 (z): the default partition's trusted time index, built without locking writes
CREATE INDEX CONCURRENTLY IF NOT EXISTS authority_log_default_recorded
  ON access.authority_log_default (domain_id, recorded_at DESC, pos DESC);
