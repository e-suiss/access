-- no-transaction
-- SEC23, SI-12, OP-55: witnessed_through reads the independent cosignatures by size, built
-- without locking writes
CREATE INDEX CONCURRENTLY IF NOT EXISTS witness_cosign_independent
  ON access.witness_cosign (domain_id, size) WHERE independent;
