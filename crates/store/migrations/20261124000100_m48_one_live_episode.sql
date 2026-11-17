-- no-transaction
-- OP-159 m.48 (d), OP-55: at most one live episode per administration line, built without locking writes
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS tenant_admin_claims_live
  ON access.tenant_admin_claims (tenant_id, environment_id, subject_id, domain_id)
  WHERE ended_ms IS NULL;
