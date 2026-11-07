-- TN-126, OP-151 m.3 (c): the first answer of a management API write under its Idempotency-Key,
-- kept 24 hours. The key is scoped to (surface, caller, key) and stored only as a digest, with
-- the digest of the request it first ran; the answer is what the API replays. Expired rows are
-- reused in place for the same scope, never deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access_ops.api_idempotency (
  scope bytea NOT NULL CHECK (octet_length(scope) = 32),
  request bytea NOT NULL CHECK (octet_length(request) = 32),
  state text NOT NULL CHECK (state IN ('running', 'done', 'released')),
  lease_until_ms bigint NOT NULL CHECK (lease_until_ms >= 0),
  expires_ms bigint NOT NULL CHECK (expires_ms >= 0),
  answer bytea CHECK (answer IS NULL OR octet_length(answer) <= 524288),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope),
  CHECK ((state = 'done') = (answer IS NOT NULL))
);

ALTER TABLE access_ops.api_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_ops.api_idempotency FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access_ops.api_idempotency FROM PUBLIC;
CREATE POLICY rows ON access_ops.api_idempotency AS PERMISSIVE USING (true);
CREATE POLICY app_only ON access_ops.api_idempotency AS RESTRICTIVE
  USING (pg_has_role(current_user, 'access_app', 'MEMBER'));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access_ops.api_idempotency
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access_ops.api_idempotency
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE (request, state, lease_until_ms, expires_ms, answer, created_at)
  ON access_ops.api_idempotency TO access_app;

RESET ROLE;
