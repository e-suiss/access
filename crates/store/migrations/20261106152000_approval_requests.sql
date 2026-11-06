-- OP-150 L6, OP-149 m.9, §9.14.1: a typed authority request a coordinator pushed to the realm's
-- Approval Surface with the approver's pre-signed contribution, kept until it expires; the
-- surface binds it to the session that opened it, the statement the approver signed and the
-- Exercise the approval became. The request stays the coordinator's (XI-7); this is its
-- short-lived copy for the surface. Rows are never deleted (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.approval_requests (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  request_id uuid NOT NULL DEFAULT uuidv7(),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  request_uri text NOT NULL CHECK (length(request_uri) BETWEEN 48 AND 255),
  request bytea NOT NULL CHECK (octet_length(request) BETWEEN 1 AND 65536),
  contribution bytea NOT NULL CHECK (octet_length(contribution) BETWEEN 1 AND 65536),
  expires_ms bigint NOT NULL CHECK (expires_ms >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  session_id uuid,
  statement bytea CHECK (statement IS NULL OR octet_length(statement) = 32),
  aas bytea CHECK (aas IS NULL OR octet_length(aas) <= 16384),
  started_ms bigint CHECK (started_ms IS NULL OR started_ms >= 0),
  finished_ms bigint CHECK (finished_ms IS NULL OR finished_ms >= 0),
  exercise bytea CHECK (exercise IS NULL OR octet_length(exercise) = 32),
  PRIMARY KEY (tenant_id, realm_id, request_id),
  UNIQUE (tenant_id, realm_id, request_uri),
  FOREIGN KEY (tenant_id, realm_id) REFERENCES access.realms (tenant_id, realm_id)
);
CREATE INDEX approval_requests_digest
  ON access.approval_requests (tenant_id, realm_id, digest, created_at DESC);

ALTER TABLE access.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access.approval_requests FORCE ROW LEVEL SECURITY;
REVOKE ALL ON access.approval_requests FROM PUBLIC;
CREATE POLICY rows ON access.approval_requests AS PERMISSIVE USING (true);
CREATE POLICY tenant_scope ON access.approval_requests AS RESTRICTIVE TO access_app
  USING (tenant_id = (SELECT access.tenant_scope()))
  WITH CHECK (tenant_id = (SELECT access.tenant_scope()));
CREATE POLICY realm_scope ON access.approval_requests AS RESTRICTIVE TO access_app
  USING (realm_id = (SELECT access.realm_scope()))
  WITH CHECK (realm_id = (SELECT access.realm_scope()));
CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.approval_requests
  FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation();
CREATE TRIGGER no_delete BEFORE DELETE ON access.approval_requests
  FOR EACH ROW EXECUTE FUNCTION access.reject_mutation();

GRANT SELECT, INSERT, UPDATE (session_id, statement, aas, started_ms, finished_ms, exercise)
  ON access.approval_requests TO access_app;

RESET ROLE;
