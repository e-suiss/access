-- no-transaction
-- TN-143, OP-55: one primary environment per tenant, built without locking writes
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS environments_one_primary
  ON access.environments (tenant_id) WHERE kind = 'primary';
