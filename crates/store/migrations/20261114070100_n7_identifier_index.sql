-- no-transaction
-- OP-153 m.3 (aa), TN-76 m.3, OP-55: the realm's blind index is unique over live and tombstoned
-- identifiers, built without locking writes
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS identity_identifiers_index_live
  ON access.identity_identifiers (tenant_id, realm_id, value_index)
  WHERE status = 'active' AND value_index IS NOT NULL;
