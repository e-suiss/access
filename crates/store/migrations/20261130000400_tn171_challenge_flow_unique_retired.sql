-- no-transaction
-- TN-171, OP-55: a flow may hold several challenges now; the one-per-flow index goes, without
-- locking writes
DROP INDEX CONCURRENTLY IF EXISTS access.identity_address_challenges_flow;
