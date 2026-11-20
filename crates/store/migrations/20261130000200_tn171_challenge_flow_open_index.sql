-- no-transaction
-- TN-171, OP-55: one open challenge per flow, the earlier ones kept beside it; built without
-- locking writes
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS identity_address_challenges_flow_open
  ON access.identity_address_challenges (tenant_id, environment_id, flow_hash)
  WHERE status = 'open';
