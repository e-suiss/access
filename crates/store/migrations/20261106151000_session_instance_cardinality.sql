-- OP-150 L6, INV-13, §7.1, §12.12/7: an identity session binds to at most one active human
-- device Instance per realm; renewing a session is not a new Instance. A retired key frees the
-- slot. Rows are never deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE UNIQUE INDEX device_keys_one_active_per_session
  ON access.device_keys (tenant_id, realm_id, session_id)
  WHERE status = 'active' AND session_id IS NOT NULL;

RESET ROLE;
