-- OP-157 m.3 (f), TN-137, XI-7, SI-21: support access requests and what became of them. An
-- operator's request is an invitation only: it names the person, the case, the scope and the
-- minutes asked for, and nothing is granted until the person's own grant.issue commits. A request
-- is declined, or granted with the Grant it became (an artifacts request with a Grant that only
-- reads the person's support artifacts); a granted request ends when its Grant reaches
-- its end or is revoked. The person's "Block support access" setting is a new version of its row.
-- Every table only grows (OP-73).
SET LOCAL ROLE access_migrator;

CREATE TABLE access.support_requests (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  request_id uuid NOT NULL DEFAULT uuidv7(),
  -- pii:none
  operator_id uuid NOT NULL,
  operator_party bytea NOT NULL CHECK (octet_length(operator_party) = 16),
  -- pii:none
  subject_id uuid NOT NULL,
  subject_party bytea NOT NULL CHECK (octet_length(subject_party) = 16),
  case_system text NOT NULL CHECK (case_system ~ '^[a-z][a-z0-9-]{0,62}$'),
  case_label text NOT NULL CHECK (case_label ~ '^[A-Za-z0-9][A-Za-z0-9._:#-]{0,63}$'),
  case_ref bytea NOT NULL CHECK (octet_length(case_ref) = 32),
  scope text NOT NULL CHECK (scope IN ('read', 'profile', 'artifacts')),
  minutes integer NOT NULL CHECK (minutes BETWEEN 1 AND 1440 AND (scope = 'read' OR minutes <= 60)),
  created_ms bigint NOT NULL CHECK (created_ms >= 0),
  expires_ms bigint NOT NULL CHECK (expires_ms > created_ms),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, request_id),
  FOREIGN KEY (tenant_id, realm_id, operator_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id),
  CHECK (operator_id <> subject_id)
);
CREATE INDEX support_requests_subject
  ON access.support_requests (tenant_id, realm_id, subject_id, expires_ms);
CREATE INDEX support_requests_operator
  ON access.support_requests (tenant_id, realm_id, operator_id, expires_ms);

CREATE TABLE access.support_request_outcomes (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  request_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('declined', 'granted', 'ended', 'revoked')),
  grant_id bytea CHECK (grant_id IS NULL OR octet_length(grant_id) = 16),
  exercise bytea CHECK (exercise IS NULL OR octet_length(exercise) = 32),
  until_ms bigint CHECK (until_ms IS NULL OR until_ms >= 0),
  position bigint CHECK (position IS NULL OR position >= 0),
  template text CHECK (template IS NULL OR template IN ('support.session', 'support.standing', 'support.artifacts')),
  at_ms bigint NOT NULL CHECK (at_ms >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, request_id, state),
  FOREIGN KEY (tenant_id, realm_id, request_id)
    REFERENCES access.support_requests (tenant_id, realm_id, request_id),
  CHECK ((state = 'granted') = (grant_id IS NOT NULL AND exercise IS NOT NULL AND until_ms IS NOT NULL
                                AND position IS NOT NULL AND template IS NOT NULL))
);
CREATE UNIQUE INDEX support_request_outcomes_answer
  ON access.support_request_outcomes (tenant_id, realm_id, request_id)
  WHERE state IN ('declined', 'granted');
CREATE UNIQUE INDEX support_request_outcomes_end
  ON access.support_request_outcomes (tenant_id, realm_id, request_id)
  WHERE state IN ('ended', 'revoked');
CREATE UNIQUE INDEX support_request_outcomes_grant
  ON access.support_request_outcomes (tenant_id, realm_id, grant_id)
  WHERE state = 'granted';
CREATE INDEX support_request_outcomes_until
  ON access.support_request_outcomes (tenant_id, realm_id, until_ms)
  WHERE state = 'granted';

CREATE TABLE access.support_blocks (
  tenant_id uuid NOT NULL,
  realm_id uuid NOT NULL,
  -- pii:none
  subject_id uuid NOT NULL,
  version bigint NOT NULL CHECK (version >= 1),
  blocked boolean NOT NULL,
  at_ms bigint NOT NULL CHECK (at_ms >= 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, realm_id, subject_id, version),
  FOREIGN KEY (tenant_id, realm_id, subject_id)
    REFERENCES access.identity_subjects (tenant_id, realm_id, subject_id)
);

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['support_requests', 'support_request_outcomes', 'support_blocks'] LOOP
    EXECUTE format('ALTER TABLE access.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE access.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON access.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY rows ON access.%I AS PERMISSIVE USING (true)', t);
    EXECUTE format('CREATE POLICY tenant_scope ON access.%I AS RESTRICTIVE TO access_app '
                   'USING (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope())) '
                   'WITH CHECK (tenant_id = (SELECT access.tenant_scope()) AND realm_id = (SELECT access.realm_scope()))', t);
    EXECUTE format('CREATE TRIGGER no_truncate BEFORE TRUNCATE ON access.%I '
                   'FOR EACH STATEMENT EXECUTE FUNCTION access.reject_mutation()', t);
    EXECUTE format('CREATE TRIGGER append_only_row BEFORE UPDATE OR DELETE ON access.%I '
                   'FOR EACH ROW EXECUTE FUNCTION access.reject_mutation()', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT ON access.support_requests, access.support_request_outcomes,
  access.support_blocks TO access_app;

RESET ROLE;
