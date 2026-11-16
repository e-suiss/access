-- no-transaction
-- TN-138, OP-55: one management environment per tenant, built without locking writes
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS environments_one_management
  ON access.environments (tenant_id) WHERE kind = 'management';
