-- no-transaction
-- TN-171, OP-55: a flow's challenges, newest first; built without locking writes
CREATE INDEX CONCURRENTLY IF NOT EXISTS identity_address_challenges_flow_created
  ON access.identity_address_challenges (tenant_id, environment_id, flow_hash, created_ms);
