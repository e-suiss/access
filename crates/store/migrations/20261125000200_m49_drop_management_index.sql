-- no-transaction
-- TN-143, OP-55: no environment is a management environment any more
DROP INDEX CONCURRENTLY IF EXISTS access.environments_one_management;
